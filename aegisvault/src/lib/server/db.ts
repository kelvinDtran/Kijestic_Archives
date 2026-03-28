/**
 * AegisVault — Prisma Database Client Singleton
 *
 * In Next.js development mode, Hot Module Replacement (HMR) causes this module
 * to be re-evaluated on every file change. Without this singleton pattern,
 * each HMR cycle would create a new PrismaClient, exhausting DB connections.
 */

import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const db =
  globalForPrisma.prisma ??
  new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['error', 'warn']
        : ['error'],
  });

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = db;
}
