local claims = {
  email_verified: false,
} + std.extVar('claims');

{
  identity: {
    traits: {
      email: claims.email,
      [if 'given_name' in claims then 'name']: {
        first: claims.given_name,
        [if 'family_name' in claims then 'last']: claims.family_name,
      },
    },
  },
}
