
# read xml, update scan folder
look in the xml file (ServiceNow Update Set format) in the /dist directory. for each scan_script_only_check record inside:

1 - get the javascript out of the payload attribute and create or update a new .js file record under scans/current directory. 
2 - for the other fields (documentation_url, priority, category, documentation_url, etc, make a JSON file with the same name as the item in 1 above.



# compare repo to XML

look in the xml file (ServiceNow Update Set format) in the /dist directory. compare the information in each file to the matching payload/section inside of the update set. make a list of all differences, grouped by the app file name in the update set. 