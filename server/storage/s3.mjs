// Vultr Object Storage through @aws-sdk/client-s3 (section 10.4): private bucket, key
// reports/<run_id>.json, checksums WHEN_REQUIRED (S3-compatible services reject the CRC32 header
// the SDK adds by default), DeleteObject one at a time (DeleteObjects still sends a checksum).
// The SDK is imported lazily so a deployment without credentials never loads it.
import { RUN_ID_RE } from '../run/ids.mjs';

export const REPORT_PREFIX = 'reports/';

export class StorageUnavailable extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.code = 'storage_unavailable';
  }
}

const keyFor = (id) => {
  if (!RUN_ID_RE.test(id)) throw new TypeError('invalid run id');
  return `${REPORT_PREFIX}${id}.json`;
};

/**
 * @param {{endpoint: string, bucket: string, accessKey: string, secretKey: string}} s3
 * @param {object} [opts]
 * @param {object} [opts.client]  a fake client with send(command) (tests)
 * @param {object} [opts.sdk]  the @aws-sdk/client-s3 module (tests)
 */
export async function createS3(s3, { client = null, sdk = null } = {}) {
  const mod = sdk ?? (await import('@aws-sdk/client-s3'));
  const { PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadBucketCommand, ListObjectsV2Command, S3Client } = mod;
  const c =
    client ??
    new S3Client({
      endpoint: s3.endpoint,
      region: 'us-east-1', // required by the SDK, meaningless for Vultr
      credentials: { accessKeyId: s3.accessKey, secretAccessKey: s3.secretKey },
      forcePathStyle: false,
      requestChecksumCalculation: 'WHEN_REQUIRED',
      responseChecksumValidation: 'WHEN_REQUIRED',
    });
  const bucket = s3.bucket;
  const isMissing = (err) => err?.name === 'NoSuchKey' || err?.name === 'NotFound' || err?.$metadata?.httpStatusCode === 404;

  return {
    bucket,
    async putReport(id, report) {
      await c.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: keyFor(id),
          Body: JSON.stringify(report),
          ContentType: 'application/json; charset=utf-8',
          Metadata: { 'schema-version': String(report?.schema_version ?? 1) },
        }),
      );
    },
    /** null when the object does not exist; throws StorageUnavailable on any other failure. */
    async getReport(id) {
      let res;
      try {
        res = await c.send(new GetObjectCommand({ Bucket: bucket, Key: keyFor(id) }));
      } catch (err) {
        if (isMissing(err)) return null;
        throw new StorageUnavailable('Object Storage GET failed', err);
      }
      // Content-Length is not trustworthy on Vultr (compat matrix): read the body to the end.
      const text = await res.Body.transformToString();
      try {
        return JSON.parse(text);
      } catch (err) {
        throw new StorageUnavailable('stored report is not valid JSON', err);
      }
    },
    async deleteReport(id) {
      await c.send(new DeleteObjectCommand({ Bucket: bucket, Key: keyFor(id) }));
    },
    async headBucket() {
      await c.send(new HeadBucketCommand({ Bucket: bucket }));
    },
    /** Every report object with its LastModified, for the daily retention sweep. */
    async listReports() {
      const out = [];
      let token;
      do {
        const page = await c.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: REPORT_PREFIX, ContinuationToken: token }));
        for (const obj of page.Contents ?? []) {
          const m = /^reports\/([0-9A-Z]{26})\.json$/.exec(obj.Key ?? '');
          if (m) out.push({ id: m[1], lastModified: obj.LastModified instanceof Date ? obj.LastModified : new Date(obj.LastModified) });
        }
        token = page.IsTruncated ? page.NextContinuationToken : undefined;
      } while (token);
      return out;
    },
    /** PUT + GET + DELETE of selftest/<ts>.json: proves credentials, path style and checksums. */
    async selftest() {
      const key = `selftest/${Date.now()}.json`;
      const body = JSON.stringify({ ok: true, ts: new Date().toISOString() });
      await c.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: body, ContentType: 'application/json; charset=utf-8' }));
      const got = await c.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
      const text = await got.Body.transformToString();
      await c.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
      if (text !== body) throw new Error('selftest: GET returned different bytes than PUT');
      return key;
    },
  };
}
