angular.module('main')

/**
 * permissions
 */
.factory('permissions', [function() {
		var vm = this;
		vm.permission = 'Permission_Guest';

		vm.checkPermit = function(perm) {
			var notFlag = perm[0] === '!';
			if (notFlag) {
				perm = perm.slice(1).trim();
			}

			var hasPermission = (vm.permission === perm);
			if (notFlag && !hasPermission || !notFlag && hasPermission) {
				return true;
			}
			return false;
		}

		return {
			setPermissions: function(username) {
				if ('Administrator' == username) {
					vm.permission = 'Permission_Admin';
				} else if ('Viewer' == username) {
					vm.permission = 'Permission_Viewer';
				} else if ('GuestOperator' == username) {
					vm.permission = 'Permission_Guest';
				}
			},
			hasPermission: function(permValue) {
				var perms = permValue.split(" ");
				var hasPermit = false;

				for (i = 0; i < perms.length; i++) {
					if (vm.checkPermit(perms[i])) {
						hasPermit = true;
						break;
					}
	     		 }
				return hasPermit;
			}
		}
	}])
	/**
	 * add deisabled attr
	 */
	.directive('operationPermission', ['permissions', function(permissions) {
		var checkPermit = function(perm) {
			var notFlag = perm[0] === '!';
			if (notFlag) {
				perm = perm.slice(1).trim();
			}
			var hasPermission = permissions.hasPermission(perm);
			if (notFlag && !hasPermission || !notFlag && hasPermission) {
				return true;
			}
			return false;
		}

		return {
			restrict: 'A',
			link: function(scope, element, attrs) {
				var optPermValue = attrs.operationPermission.trim();
				var hasPermit = permissions.hasPermission(optPermValue);
				if (!hasPermit) {
					element.attr('disabled', 'true');
				}
			}
		};
	}])
	/**
	 * remove element
	 */
	.directive('displayPermission', ['permissions', function(permissions) {
		var removeElement = function(element) {
			element && element.remove && element.remove();
		}
		return {
			restrict: 'A',
			link: function(scope, element, attrs) {
				var diPermValue = attrs.displayPermission.trim();
				var hasPermit = permissions.hasPermission(diPermValue);
				if (!hasPermit) {
					angular.forEach(element.children(), function(child) {
						removeElement(child);
					});
					removeElement(element);
				}
			}
		};
	}])

;