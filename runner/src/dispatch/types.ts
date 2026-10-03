/**
 * Tool-dispatch result type (v0.19.0 refactor — extracted from dispatch.ts).
 */
export interface DispatchResult {
  result: string;
  attackId?: string;
  target?: string;
  opsec?: string;
}

