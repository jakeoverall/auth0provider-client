const assert = require('assert');
const { hasPermissions, setInstance } = require('../lib/Auth0Provider');
const { describe, it } = require('node:test');

const mockInstance = {
  hasPermissions: (permissions) => {
    const userPermissions = ['read', 'write', 'delete'];
    if (Array.isArray(permissions)) {
      return permissions.every(permission => userPermissions.includes(permission));
    }
    return userPermissions.includes(permissions);
  }
};

// Inject the mock instance into the module
setInstance(mockInstance);

describe('Auth0Provider', function () {
  describe('hasPermissions', function () {
    it('should return true for a single permission that the user has', function () {
      assert.strictEqual(hasPermissions('read'), true);
    });

    it('should return false for a single permission that the user does not have', function () {
      assert.strictEqual(hasPermissions('execute'), false);
    });

    it('should return true for multiple permissions that the user has', function () {
      assert.strictEqual(hasPermissions(['read', 'write']), true);
    });

    it('should return false for multiple permissions if the user lacks any of them', function () {
      assert.strictEqual(hasPermissions(['read', 'execute']), false);
    });

    it('should return true for an empty array of permissions', function () {
      assert.strictEqual(hasPermissions([]), true);
    });
  });
});