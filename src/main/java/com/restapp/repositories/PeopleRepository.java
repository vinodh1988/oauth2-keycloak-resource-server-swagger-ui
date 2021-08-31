package com.restapp.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.restapp.entities.Person;

public interface PeopleRepository extends JpaRepository<Person, Long> {
    public Person findBySno(Integer sno);
    
    @Query("from Person p where sno between :start and :end")
    public List<Person> peopleByRange(@Param("start")int start,@Param("end") int end);
}
