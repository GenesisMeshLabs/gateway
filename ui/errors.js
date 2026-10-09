// Plain-language explanations of refused requests, for the console. Pure
// functions of the status, the parsed body and the response headers, so
// tools/test_ui_errors.mjs can check them without a browser.

/** The error code in a gateway body ({error, code}) or an authority body ({error: {code}}). */
export function errorCode(data){
  if(!data||typeof data!=='object')return '';
  if(data.error&&typeof data.error==='object'&&typeof data.error.code==='string')return data.error.code;
  return typeof data.code==='string'?data.code:'';
}

/** The message in either body shape. */
export function errorMessage(data){
  if(typeof data==='string')return data.slice(0,200);
  if(!data||typeof data!=='object')return '';
  if(typeof data.error==='string')return data.error;
  return typeof data.error?.message==='string'?data.error.message:'';
}

function header(headers,name){
  return typeof headers?.get==='function'?headers.get(name):headers?.[name];
}

/** "Wait N seconds" from Retry-After, or a generic wait. */
function wait(headers){
  const value=header(headers,'retry-after');
  const seconds=/^\d{1,5}$/.test(value??'')?Number(value):NaN;
  if(!Number.isInteger(seconds))return 'Wait before retrying.';
  return 'Wait '+seconds+' second'+(seconds===1?'':'s')+' before retrying.';
}

/**
 * What a refused request means and what to do about it. `fromAuthority`
 * says the request was an authority operation forwarded by the gateway.
 */
export function explainFailure(status,data,headers,fromAuthority=false){
  const code=errorCode(data);
  if(status===429){
    if(code==='admin_auth_throttled')return 'Too many failed operator signatures from this address with this key. '+wait(headers)+' Then check the operator key ID, the seed and this computer\'s clock.';
    if(code==='rate_limited'&&!fromAuthority)return 'Your service token used its request quota for this minute. '+wait(headers);
    return 'The authority is limiting requests from this gateway. '+wait(headers);
  }
  if(status===401){
    if(fromAuthority&&code!=='unauthorized')return 'The authority refused the operator signature ('+(code||'admin_auth_failed')+'). Check the operator key ID and seed, and that this computer\'s clock is correct.';
    return 'The service token was refused. Check it, then select Connect again.';
  }
  if(status===403){
    if(code==='insufficient_operator_tier')return 'This operator key\'s tier does not allow this operation. Sign with a key of the required tier: '+(errorMessage(data)||'see the authority\'s operator key tiers.');
    return 'Your service identity does not have access to this operation.';
  }
  const message=errorMessage(data);
  return 'Request rejected ('+status+')'+(message?': '+message:'');
}

/** The gateway's request ID, and the authority's when it sent one. */
export function requestIds(headers){
  const own=header(headers,'x-request-id')||'unavailable';
  const upstream=header(headers,'x-upstream-request-id');
  return 'Request ID: '+own+(upstream?' | Authority request ID: '+upstream:'');
}
