// AWS Cognito (extracted from the SURU app's amplifyconfiguration.json)
export const COGNITO_REGION = 'eu-central-1';
export const COGNITO_POOL_ID = 'eu-central-1_8hkX7Bvjh';
export const COGNITO_CLIENT_ID = '1p3lj6d18fehl88ugahglf6kc8';
export const COGNITO_IDP_URL = `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/`;

// SURU backend (AWS API Gateway, eu-central-1)
export const API_BASE = 'https://api.freeze.suru-cloud.com/v2';

// Polling interval in minutes
export const DEFAULT_SCAN_INTERVAL_MINUTES = 60;
export const MIN_SCAN_INTERVAL_MINUTES = 5;
export const MAX_SCAN_INTERVAL_MINUTES = 1440;
