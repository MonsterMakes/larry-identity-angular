export interface ErrorDetails {
	error: string; //short description of the error
	error_description: string; // more detailed description of the error
	additional_details?: object; // An object with additional details
}