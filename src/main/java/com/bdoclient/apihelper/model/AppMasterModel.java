package com.bdoclient.apihelper.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity(name = "api_master")
@NoArgsConstructor
@AllArgsConstructor
public class AppMasterModel {

	@Id
	@GeneratedValue
	private Long id;

	
	@Column(name = "bdo_userid")
	private String bdoUserId;
	
	@Column(name = "bdo_auth_token")
	private String bdoAuthToken;
	
	@Column(name = "nic_auth_token")
	private String nicAuthToken;
	
	@Column(name = "appkey")
	private String appKey;
	
	@Column(name = "sek")
	private String sek;
	
	@Column(name = "api_type")
	private String apiType;
	
	
}
