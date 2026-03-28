/**
 * Prisma seed — development only
 * Run: npm run db:seed
 */

import { PrismaClient } from '@prisma/client';

const db = new PrismaClient();

async function main() {
  console.log('Seed complete. No seed data defined for AegisVault — create your account via the UI.');
}

main()
  .catch(console.error)
  .finally(() => db.$disconnect());
