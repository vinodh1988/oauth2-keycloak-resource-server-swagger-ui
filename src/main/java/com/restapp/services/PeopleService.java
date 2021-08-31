package com.restapp.services;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.rest.util.RecordAlreadyExists;
import com.rest.util.RecordNotExists;
import com.restapp.entities.Person;
import com.restapp.repositories.PeopleRepository;

@Service
public class PeopleService {
	
	@Autowired
	PeopleRepository people;
	
	@PostConstruct
	public void init() {
		System.out.println("People Service Ready...!!!");
		System.out.println(people);
		System.out.println(people.getClass());
	}
	
   public List<Person> getPeople(){
	   List<Person> list=new ArrayList<Person>();
	   list.add(new Person(1,"Harry","Chennai"));
	   list.add(new Person(2,"Krishna","Indore"));
	   list.add(new Person(3,"Ram","Bangalore"));
	   list.add(new Person(4,"Mahesh","Mumbai"));
	   return list;
   }
   
   public List<Person> getPeople2(){
	   
	   return people.findAll();
   }
   
   public void addPeople(Person p) throws RecordAlreadyExists{
	
	  Person result = people.findBySno(p.getSno());
	  if(result!=null)
		   throw new RecordAlreadyExists();
	  else
	  {
		  people.save(p); // Save method updates the record if it sno already exists
	  }
   }
   
   public void updatePeople(Person p) throws RecordNotExists{
	   Person result = people.findBySno(p.getSno());
		  if(result==null)
			   throw new RecordNotExists();
		  else
		  {
			  people.save(p); // Save method updates the record if it sno already exists
		  }
   }
   
   public void deletePeople(Integer sno) throws RecordNotExists
   {  
	   Person result = people.findBySno(sno);
		  if(result==null)
			   throw new RecordNotExists();
		  else
		  {
			  people.delete(result); // Save method updates the record if it sno already exists
		  }
   }
   
   public List<Person> getRange(Integer start, Integer end){
	   return people.peopleByRange(start, end);
   }
   
}
