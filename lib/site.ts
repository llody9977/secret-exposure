export const basePath = process.env.SITE_BASE_PATH ?? '/secret-exposure';
export const origin = 'https://llody9977.github.io';
export const path = (value: string) => `${basePath}${value}`;
