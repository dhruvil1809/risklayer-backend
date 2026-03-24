echo "Installing dependencies..."
npm install

echo "Generating Prisma client..."
npx prisma generate

echo "Installing Playwright browsers..."
npx playwright install --with-deps

echo "Build completed!"


git init
git add .
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/dhruvil1809/risklayer-backend.git
git push -u origin main