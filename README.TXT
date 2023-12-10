
##CSC 361: A1 Smart Client Documentation


## Running smart_client.py
1. Install Python 3.8.10 or higher
2. Open Terminal on UNIX based OS
3. Navigate to the directory containing smart_client.py
4. Execute the following command in Terminal:

    python3 smart_client.py <URI>
	

#Examples:
python3 smart_client.py www.motorolasolutions.com
python3 smart_client.py https://www.motorolasolutions.com
python3 smart_client.py https://www.motorolasolutions.com/en_us/products/p25-products/apx-next-story.html

python3 smart_client.py www.youtube.com
python3 smart_client.py https://www.youtube.com
python3 smart_client.py https://www.youtube.com/watch?v=lj1Dw_NxmaI


*********************
***** IMPORTANT *****
*********************
-The http:// prefix can be omitted or included
-If more than one URI is passed, the program will only accept the first
-A path name can be included after the host
-No input will cause the program to terminate
-HTTP status codes checked are 302, 301, 401, 400. Any others are NOT checked for
-There may be no cookies returned for some websites
