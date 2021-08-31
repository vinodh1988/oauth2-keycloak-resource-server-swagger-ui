package com.restapp.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.rest.util.RecordAlreadyExists;
import com.rest.util.RecordNotExists;
import com.restapp.entities.Person;
import com.restapp.services.PeopleService;

@RestController
@RequestMapping("/api")
public class PeopleAPI implements PeopleAPISpecification {
@Autowired
	  PeopleService people;

@GetMapping("/people")
   public List<Person> getPeople(){
	   return people.getPeople();
   }

@GetMapping("/db/people")
public List<Person> getPeople2(){
	   return people.getPeople2();
}


@GetMapping("/db/people/{start}/{end}")
public List<Person> getPeople2(@PathVariable Integer start,@PathVariable Integer end){
	   return people.getRange(start, end);
}

@PostMapping("/db/people")
public ResponseEntity<Person> addPeople(@RequestBody Person person) {
	try {
		people.addPeople(person);
		return new ResponseEntity<Person>(person,HttpStatus.CREATED);
	}
	catch(RecordAlreadyExists e) {
		return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
	}
}

@PatchMapping("/db/people")
@PutMapping("/db/people")
public ResponseEntity<Person> updatePeople(@RequestBody Person person) {
	try {
		people.updatePeople(person);
		return new ResponseEntity<Person>(person,HttpStatus.CREATED);
	}
	catch(RecordNotExists e) {
		
		return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
	}
}

@DeleteMapping("/db/people/{sno}")
public ResponseEntity<String> deletePeople(@PathVariable Integer sno){
	try {
		people.deletePeople(sno);
		return new ResponseEntity<String>("Deleted Successfully",HttpStatus.CREATED);
	}
	catch(RecordNotExists e) {
		
		return new ResponseEntity<>("No Such Record Exists",HttpStatus.INTERNAL_SERVER_ERROR);
	}
}

@RequestMapping(
		  value = "/images/{sno}",
		  produces = MediaType.IMAGE_PNG_VALUE
		)
		public @ResponseBody byte[] getImageWithMediaType(@PathVariable Integer sno) throws IOException {
	     File f=new File("E:\\images\\pic"+sno+".png");
		    FileInputStream in = new FileInputStream(f);
		    return IOUtils.toByteArray(in);
		}

@PostMapping("/uploads/pics")
public ResponseEntity<String> addFile(@RequestParam("file") MultipartFile file,@RequestParam("sno") Integer sno,@RequestParam("name") String name, @RequestParam("city") String city)
{
	 if(file.isEmpty()){
		 return new ResponseEntity<String>("File not attached",HttpStatus.BAD_REQUEST);
	 }
	
	 else{
		 String allowed[]={"jpg","jpeg","png","gif"};
		 Boolean valid=false;
		 String extension=FilenameUtils.getExtension(file.getOriginalFilename());
		 for(String x:allowed){
			 if(x.contentEquals(extension)){
				 valid=true;
				 break;
			 } 
		 }
		 if(valid){
			 try {
				 byte b[]=file.getBytes();
				 Path p=Paths.get("e:\\images\\"+file.getOriginalFilename());
				 Files.write(p,b);
			 } 
			 catch (IOException e) {
			// TODO Auto-generated catch block
				 	e.printStackTrace();
				 	return new ResponseEntity<String>("Error in Writing",HttpStatus.INTERNAL_SERVER_ERROR);
			 }
			 try {
				people.addPeople(new Person(sno,name,city));
			} catch (RecordAlreadyExists e) {
				// TODO Auto-generated catch block
				return new ResponseEntity<String>("Record Already Exists",HttpStatus.INTERNAL_SERVER_ERROR); 
			}
			 return new ResponseEntity<String>("File uploaded successfully",HttpStatus.OK);
		 }
		 
		 return new ResponseEntity<String>("Only png,jpeg,jpg and gif allowed",HttpStatus.BAD_REQUEST); 
	 }}
	
}



