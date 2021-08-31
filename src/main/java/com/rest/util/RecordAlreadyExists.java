package com.rest.util;

public class RecordAlreadyExists extends Exception {
     
	public String getMessage() {
		return toString();
	}
	
	public String toString() {
		return "Record Already Exists";
	}
	
}
