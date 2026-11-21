import { merge } from 'lodash';
import http from '@acme/http/client';
import { helper } from './util';

export const run = () => merge({}, http, helper);
