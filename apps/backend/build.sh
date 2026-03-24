echo "Installing dependencies..."
npm install

echo "Generating Prisma client..."
npx prisma generate

echo "Installing Playwright browsers..."
npx playwright install --with-deps

echo "Build completed!"