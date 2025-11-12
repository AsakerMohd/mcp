#!/usr/bin/env node
import 'dotenv/config';
import * as cdk from 'aws-cdk-lib';
import { EKSAppStack, AppConfig } from '../lib/cdk-stack';
import * as fs from 'fs';
import * as path from 'path';

const app = new cdk.App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const configDir = path.join(__dirname, '../config');
const configFiles = fs.readdirSync(configDir).filter(f => f.endsWith('.json'));

configFiles.forEach(configFile => {
  if (configFile.includes('..') || configFile.includes('/') || configFile.includes('\\')) {
    throw new Error(`Invalid config file name: ${configFile}`);
  }

  const configPath = path.join(configDir, configFile);
  const config: AppConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

  const stackId = config.appName
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join('') + 'Stack';

  new EKSAppStack(app, stackId, config, { env });
});

app.synth();