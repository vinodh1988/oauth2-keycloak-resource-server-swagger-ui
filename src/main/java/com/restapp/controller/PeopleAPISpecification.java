package com.restapp.controller;

import java.io.IOException;
import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.restapp.entities.Person;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@Api
public interface PeopleAPISpecification {
	@ApiOperation(value="list of people and it is static data",response=Iterable.class)
	 public List<Person> getPeople();
	@ApiOperation(value="list of people from database",response=Iterable.class)
	 public List<Person> getPeople2();
	@ApiOperation(value="list of people from database in given range",response=Iterable.class)
	 public List<Person> getPeople2(@PathVariable Integer start,@PathVariable Integer end);
	@ApiOperation(value="Add a new person into Database",response=Person.class)
	 public ResponseEntity<Person> addPeople(@RequestBody Person person);
	@ApiOperation(value="Update existing person data",response=Person.class)
	 public ResponseEntity<Person> updatePeople(@RequestBody Person person);
	@ApiOperation(value="Deletes person if exists",response=Iterable.class)
	 public ResponseEntity<String> deletePeople(@PathVariable Integer sno);
	@ApiOperation(value="returns pic with given ID",response=Iterable.class)
	 public @ResponseBody byte[] getImageWithMediaType(@PathVariable Integer sno) throws IOException;
	@ApiOperation(value="Upload person data and pic file",response=Iterable.class)
	 public ResponseEntity<String> addFile(@RequestParam("file") MultipartFile file,@RequestParam("sno") Integer sno,@RequestParam("name") String name, @RequestParam("city") String city);

}
