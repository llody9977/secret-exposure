import type { NextConfig } from 'next';
const nextConfig: NextConfig = {
  output: 'export',
  trailingSlash: true,
  basePath: process.env.SITE_BASE_PATH ?? '/secret_exposure',
};
export default nextConfig;
