package com.security.springSecurityJWT.repositories;

import com.security.springSecurityJWT.models.RoleEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IRolesRepository extends CrudRepository<RoleEntity,Long> {


}
