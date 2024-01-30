package io.security.corespringsecurity.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import io.security.corespringsecurity.domain.entity.Resources;

public interface ResourcesRepository extends JpaRepository<Resources, Long> {

    Resources findByResourceNameAndHttpMethod(String resourceName, String httpMethod);

    @Query("select r from Resources r join fetch r.roleSet where r.resourceType = 'url' order by r.orderNum desc")
    List<Resources> findAllResources();

}
