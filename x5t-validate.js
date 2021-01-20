const crypto = require('crypto');
const https = require('https');
const url = require('url');

const request = (jwkUrl) => new Promise((resolve, reject) => {

  const jwkUrlParsed = url.parse(jwkUrl);
  const options = {
    hostname: jwkUrlParsed.hostname,
    port: 443,
    path: jwkUrlParsed.path,
    method: 'GET',
  };

  const req = https.request(options, (res) => {
    res.setEncoding('utf8');
    let body = '';
    res.on('data', (chunk) => {
      body += chunk;
    });

    res.on('end', () => {
      const statusCode = parseInt(res.statusCode, 10);
      if (statusCode === 200) return resolve(JSON.parse(body));
      reject(new Error('UNEXPECTED HTTP RESPONSE CODE'));
    });
  });

  req.on('error', (e) => reject(e));
  req.end();
});

const tbPrintBase64UrlEncoded = (keyB64, alg) => {

  const shasum = crypto.createHash(alg)
  const keyDecoded = Buffer.from(keyB64, 'base64')
  shasum.update(keyDecoded)
  const binary = shasum.digest('binary');
  return (Buffer.from(binary, 'binary').toString('base64')).replace(/=/g, '').replace(/\//g, '_').replace(/\+/g, '-');
};

(async () => {
  try {
    const jwk = await request(process.argv[2]);

    /* sha256 */
    console.log('-----------------------------------------------------------------------------------------------------------')
    console.log('------------------------------------------------[ x5t#S256 ]-----------------------------------------------')
    console.log('-----------------------------------------------------------------------------------------------------------')
    const x5t256Calculated = tbPrintBase64UrlEncoded(jwk.keys[0].x5c[0], 'sha256');
    console.log(`calculated x5t#S256: ${x5t256Calculated}`);
    if (jwk.keys[0]["x5t#S256"]) {
      console.log(`obtained   x5t#S256: ${jwk.keys[0]["x5t#S256"]}`);

      if (jwk.keys[0]["x5t#S256"] === x5t256Calculated) console.log('>>> Success, they are identical. <<<');
      else console.log('!!! Failure, they are not identical. !!!');
    } else {
      console.log('!!! No x5t#S256 in jwk found. !!!');
    }

    /* sha1 */
    console.log('-----------------------------------------------------------------------------------------------------------')
    console.log('--------------------------------------------------[ x5t ]--------------------------------------------------')
    console.log('-----------------------------------------------------------------------------------------------------------')
    const x5tCalculated = tbPrintBase64UrlEncoded(jwk.keys[0].x5c[0], 'sha1');
    console.log(`calculated x5t: ${x5tCalculated}`);
    if (jwk.keys[0]["x5t"]) {
      console.log(`obtained   x5t: ${jwk.keys[0].x5t}`);

      if (jwk.keys[0].x5t === x5tCalculated) console.log('>>> Success, they are identical. <<<');
      else console.log('!!! Failure, they are not identical. !!!');
    } else {
      console.log('!!! No x5t in jwk found. !!!');
    }

  } catch (error) {
    console.log(error);
  }
})();
