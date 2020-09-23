package com.bdoclient.apihelper.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bdoclient.apihelper.model.AppMasterModel;

public interface AppMasterRepository extends JpaRepository<AppMasterModel, Long> {

}
