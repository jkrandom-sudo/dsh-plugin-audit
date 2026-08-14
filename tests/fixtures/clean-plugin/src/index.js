// Fixture: a well-behaved zero-dependency plugin.
export const inject = ['tools']

export function apply(ctx) {
  ctx.logger.info('clean fixture loaded')
}
