// Content: Enum for roles

package com.learning.security.enums;

public enum ERole {
    ROLE_CUSTOMER,
    ROLE_PLANT_MANAGER,
    ROLE_ADMIN

}
/*

Spring Security expects roles to have the prefix ROLE_ by default.
When you use hasRole('ADMIN'), Spring internally checks for the authority ROLE_ADMIN.
If your roles in the database are stored as ADMIN, USER, etc., without the ROLE_ prefix, it might not match what Spring expects and you might get an Access Denied error.
 */