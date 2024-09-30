package com.pcgs.spring.securitypoc.repository;

import com.pcgs.spring.securitypoc.model.Contact;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ContactRepository extends CrudRepository<Contact, String> {


}
