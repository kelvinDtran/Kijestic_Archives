/**
 * POST /api/auth/mfa/telegram/webhook — Telegram Bot webhook endpoint
 *
 * Called by Telegram servers when a user sends a message to the bot.
 * No authentication required — this is an inbound webhook from Telegram.
 *
 * Security: Optionally validates the X-Telegram-Bot-Api-Secret-Token header
 * if TELEGRAM_WEBHOOK_SECRET env var is set.
 *
 * Always returns HTTP 200 — Telegram requires 200 even for error cases.
 */

import { NextRequest, NextResponse } from 'next/server';
import { completeTelegramLink } from '@/lib/auth/telegram-otp';

// ── Types ─────────────────────────────────────────────────────────────────────

interface TelegramUser {
  id: number;
}

interface TelegramChat {
  id: number;
}

interface TelegramMessage {
  from?: TelegramUser;
  chat:  TelegramChat;
  text?: string;
}

interface TelegramUpdate {
  update_id: number;
  message?:  TelegramMessage;
}

// ── Telegram API helper ───────────────────────────────────────────────────────

async function sendTelegramMessage(chatId: number, text: string): Promise<void> {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) return;

  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
  await fetch(url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ chat_id: chatId, text }),
  }).catch((err) => {
    console.error('[Telegram webhook] Failed to send reply:', err);
  });
}

// ── POST Handler ──────────────────────────────────────────────────────────────

export async function POST(req: NextRequest): Promise<NextResponse> {
  // Optional webhook secret verification
  const webhookSecret = process.env.TELEGRAM_WEBHOOK_SECRET;
  if (webhookSecret) {
    const headerSecret = req.headers.get('X-Telegram-Bot-Api-Secret-Token');
    if (headerSecret !== webhookSecret) {
      // Return 200 to avoid Telegram retrying (but do nothing)
      return NextResponse.json({ ok: true }, { status: 200 });
    }
  }

  let update: TelegramUpdate;
  try {
    update = (await req.json()) as TelegramUpdate;
  } catch {
    return NextResponse.json({ ok: true }, { status: 200 });
  }

  const message = update.message;
  if (!message || typeof message.text !== 'string') {
    return NextResponse.json({ ok: true }, { status: 200 });
  }

  const chatId = message.chat.id;
  const text   = message.text.trim();

  // Only handle /start LINK_CODE messages
  if (!text.startsWith('/start ')) {
    await sendTelegramMessage(
      chatId,
      'Welcome to AegisVault Bot. To link your Telegram account, use the link from AegisVault settings.',
    );
    return NextResponse.json({ ok: true }, { status: 200 });
  }

  const linkCode = text.slice('/start '.length).trim();

  if (!linkCode) {
    await sendTelegramMessage(
      chatId,
      '❌ Invalid link. Please generate a new one in AegisVault settings.',
    );
    return NextResponse.json({ ok: true }, { status: 200 });
  }

  try {
    const userId = await completeTelegramLink(linkCode, BigInt(chatId));

    if (userId) {
      await sendTelegramMessage(
        chatId,
        '✅ Your Telegram account has been linked to AegisVault. You\'ll receive login codes here.',
      );
    } else {
      await sendTelegramMessage(
        chatId,
        '❌ Invalid or expired link code. Please generate a new one in AegisVault settings.',
      );
    }
  } catch (err) {
    console.error('[Telegram webhook] Error completing link:', err);
    await sendTelegramMessage(
      chatId,
      '❌ Something went wrong. Please try again or generate a new link in AegisVault settings.',
    );
  }

  // Always return 200 — Telegram requires this
  return NextResponse.json({ ok: true }, { status: 200 });
}
