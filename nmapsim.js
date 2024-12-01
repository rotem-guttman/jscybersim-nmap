// Copyright 2024 Rotem Guttman

// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file of this repository or at: 
// https://github.com/rotem-guttman/jscybersim-nmap/blob/main/LICENSE.md

// This is a quick hacked together demo of how to generate lightweight nmap-style output in javascript. 
// The intent is for this code to be used to dynamically generate nmap output that matches a problem set
// in an intelligent tutor system (ITS). There is definately a lot of room for improvement, 
// but this is functional enough for an initial prototype to user test with. 
// If you do find this useful, please reach out! I'm always looking for collaborators.

// In general, if you're just looking to use this functionality, you can skip reading everything but the CSV formatting listed below, and how to call createPortScanResults()
// createPortScanResults() will return a text buffer of your nmap output. I've included detailed comments that should help with understanding the code (and troubleshooting!)

// CSV FORMAT EXMAPLE: 
// This section should not be used in a deployed tutor - the tutor should dynamically generate the data, or load it from a csv file hosted in a /assets directory of the tutor or on the cdn.
// I broke it apart into multiple lines for readability, but obviously that isn't required. 
let exampledata = "IP,PortsOpen,PortsClosed,PortsFiltered,Latency\n"
+ "172.16.0.1,22 53 80 443,,,0.062\n"
+ "172.16.0.2,22 53 80 443,,,0.051\n"
+ "172.16.0.3,22 53 80 123 389 443,,,0.044\n"
+ "172.16.5.5,22 53 80 443,,,0.004\n"
+ "172.16.9.10,22 53 80 88 135 139 389 443 445 464,,,0.083\n"
+ "172.16.31.100,22 53 80 139 443 445,,,0.039\n"
+ "172.16.31.101,22 53 80 139 443 445,,,0.037\n"
+ "172.16.31.102,22 53 80 139 443 445 6886,,,0.29\n"
+ "8.8.8.8,100,200,300,0.666\n";

// Here we're going to convert the CSV into an actual object. If you're generating the network map dynamically then skip all this and just hand an object to createPortScanResults(). 
// The object should be in the format of a list of objects (1 per IP'ed NIC). 
// Each object should have the format: { IP: "address_string", Latency: "delay_in_seconds", PortsClosed: "space_separated_list_of_ports", PortsFiltered: "space_separated_list_of_ports", PortsOpen: "space_separated_list_of_ports" }
var testdata = $.csv.toObjects(exampledata);

// For the demo, lets just shove a new div onto the page to hold the results. 
var h1 = document.createElement("div");

// The only important attribute for correct formatting is setting white-space to pre, so that the output is spaced reasonably. 
// You'll probably also want to give it a terminal-looking font and maybe a black background with white or text to contrast the element with the rest of the tutor. 
// You could even give it a full console-looking UI, but that might be a distractor (great thing to test in a user study!)
h1.setAttribute('style', 'white-space: pre;');

// Helper functions to bit-twiddle between integer and dotted-quad representation of IPs.
function int2ip (ip) {
    return ( (ip>>>24) +'.' + (ip>>16 & 255) +'.' + (ip>>8 & 255) +'.' + (ip & 255) );
}
function ip2int(ip) {
    return ip.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
}

//  Helper function to convert a mask into its related integer (taking into account that javascript uses 64 bits but acts like it's 32 bits when doing bit operations.
function subnetMaskToNumber(mask)
{
  return (0xffffffff << (32 - Number(mask))) & 0xffffffff;
}


// There are numerous ways that nmap supports inputting the target addresses. Unforunately we need to support a large subset of these in order to ensure that most reasonable student input will be accepted, even if the way the student decides to specify the list of addresses is not intuitive to us. 
// Not only are the input options numerous, but they can be combined. As such, I repeatedly carve off the last item of the command line, and attempt to parse it as each option, then repeat, until no matching items are found. 
// Currently the system supports:
// * IPv4 addresses specified with:
//   - Individual IP address specification 
//   - CIDR address blocks
//   - Start/Stop addresses ranges (specified with a hyphen between the fully specified addresses)
//   - nmap's unique (as far as I know) use of a per-octet start-stop range. This can appear in any one of the four octets. Example: 1-2.3-4.5.7-10 
function ListIPAddresses (commandString) {

  // The list of addresses will be stored here until we're done and ready to return it. 
  let addressList = [];

  // Since we will be iteratively checking the last element in the input command, we need to check if it matches any of the formats. This regex should match all cases. It is anchored only at the END of the string, and will ignore the beginning - so you can pass in the entire nmap command, and it will ignore everything but the addresses.
  // NOTE! You'll want to make sure you're stripping any trailing whitespace characters (like a newline) from the command, if your tutor captures that input from the student hitting enter on the command. 
  var testAnyMatch = new RegExp(/(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\-(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$|(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\/([4-9]|(3[0-2]?)|(2[0-9]?)|(1[0-9]?)))?$|(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\-(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))?\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\-(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))?$/); 
  let allAddresses = commandString.match(testAnyMatch);
  
  // Since we may be testing these more than once, lets create an actual regex object for each command type. 
  // NOTE: You want these tests to be mutually exclusive. Each input on the command line can only match one type.
  // As such, we want to ensure that we test the single-IP address case AFTER the start/stop ranges, as the last element of either of those could also match a single-ip address regex. 
  // For example "sudo nmap 1.1.1.1-2.2.2.2" would match both for a range as "1.1.1.1-2.2.2.2" but also "2.2.2.2" as a single IP address. 
  var testStartStop = new RegExp(/(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\-(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/);
  var testNmapHyphenOrSingle = new RegExp(/(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\-(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))?\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\-(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))?$/);
  var testCIDR = new RegExp(/(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\/([4-9]|(3[0-2]?)|(2[0-9]?)|(1[0-9]?)))+$/);
  var testSingleIP = new RegExp(/^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/);
  
  // If the 'anything matched' regex returns a result, that means the last element still in the buffer that needs to be processed. Once all the address specifications are done, the last element will be part of the nmap command, such as flags or port specifications, and won't match. 
  while (allAddresses != null)
  {
    //Check for start-stop address notation
		if ( testStartStop.test(allAddresses[0]))
    {
      // Each option will have a helpful console logging output option. If your nmap command isn't giving you the expected results, try uncommenting all of these to make sure it's being parsed as the correct type of address specification.
    	// console.log("detected start-stop notation! " + allAddresses[0]);
      let startAddress = allAddresses[0].split("-")[0];
      let endAddress = allAddresses[0].split("-")[1];     
      startAddress = ip2int(startAddress);
      endAddress = ip2int(endAddress);
      for (let i = startAddress; i <= endAddress; i++)
      {
      	addressList.push(int2ip(i));
      }   
    } else if ( testCIDR.test(allAddresses[0]))
    { 
      // if not start/stop, check for CIDR address notation
      // console.log("detected CIDR notation! " + allAddresses[0]);
      let givenAddress = allAddresses[0].split("/")[0];
      let cidrSize = allAddresses[0].split("/")[1];   
      let startAddress = ip2int(givenAddress);
      startAddress = startAddress & subnetMaskToNumber(cidrSize); 
      var endAddress = Math.pow(2, 32-cidrSize) + startAddress -1;      
      for (let i = startAddress; i <= endAddress; i++)
      {
      	addressList.push(int2ip(i));
      }
    } else if ( testSingleIP.test(allAddresses[0]))
    { 
      // if not start/stop, or CIRD notation, check for a single regular IP address. 
    	// console.log("detected single IP notation! " + allAddresses[0]);      
      addressList.push(allAddresses[0]);
    } else if ( (testNmapHyphenOrSingle.test(allAddresses[0])) && (!testSingleIP.test(allAddresses[0])) )    
		{ 
      // If not start/stop, and not CIDR and not Single IP check for nmap hyphen notation (but check it isn't a single IP address)
    	// console.log("detected nmap-hyphen notation! " + allAddresses[0]); 
      let octA, octB, octC, octD; 
      [octA, octB, octC, octD] = allAddresses[0].split(".");			

      // This is dirty but understandable, so I'm leaving it for now.
      // If those code goes to production, and readability/understanding the code isn't the primary concern, please for the love of god
      // split these out so you're not changing data types in the same variable...
      // Each octet variable is going to hold that octet's data. Initially it will either be a number or a range.
      // Example: 1 or 1-255
      // This will be parsed into a list, either of the full range, or the number.       
      if (octA.includes("-")) { octA = _.range(octA.split("-")[0], Number(octA.split("-")[1]) +1 ) }
      else {octA = [ Number(octA) ] }
      
      if (octB.includes("-")) { octB = _.range(octB.split("-")[0], Number(octB.split("-")[1]) +1 ) }
      else {octB = [ Number(octB) ] }
      
      if (octC.includes("-")) { octC = _.range(octC.split("-")[0], Number(octC.split("-")[1]) +1 ) }
      else {octC = [ Number(octC) ] }
      
      if (octD.includes("-")) { octD = _.range(octD.split("-")[0], Number(octD.split("-")[1]) +1 ) }
      else {octD = [ Number(octD) ] }

      // Iterate over all the combinations and add the addresses included to the list. 
      for (let octetA of octA) 
      {
      	for (let octetB of octB)
        {
        	for (let octetC of octC)
          {
          	for (let octetD of octD)
            {
            	addressList.push(octetA +"."+ octetB +"."+ octetC +"."+ octetD);
            }
          }
        }
      }                      
    }    
		
    // Now that we've dealt with that input, we should remove it and try to parse the command line again in case there were multiple groups of addresses provided.   	
    // Note that we need to trim the whitespace again! 
    commandString = commandString.replace(allAddresses[0], "").trim();
    
    // Try to parse the command again to see if there are more address groups to cover. This will be tested back at the top of the loop. 
    allAddresses = commandString.match(testAnyMatch);
  }
  
  // if there are no more address groups to cover, return the results. 
  return addressList; 
}

// This will be the 'main' command which you will call. Returns a text buffer with nmap formatted output. 
// data - A list of objects describing the entities visible to the scanner on the network in the format specified at the start of this file. 
// commandString - the string the student used to invoke the nmap command. 
function createPortScanResults(data, commandString) {
  var result = "Starting Nmap 7.95 ( https://nmap.org )\r\n";
  let scannedaddresses = 0;
  var pingScan = commandString.includes(" -sn ") ||  commandString.includes(" -PE ");
  var targetlist = ListIPAddresses(commandString);

  // The two main things that are going to determine what your putput looks like are the type of scan (ping scan or port scan) and the list of targets to scan. 
  // if you're getting strange output, start by uncommenting these three lines to make sure the command is being parsed as you intended. 
  // console.log("Ping scan? " + pingScan);
  // console.log("Target List:);
  // console.log(targetlist);
  
  let totaladdresses = targetlist.length;
  for (let machine in data) {
    // Remember that we're not ACTUALLY scanning the network. It's far more efficient for us to iterate over the possible results and check if they were scanned for, then to actually check every scan target
    // This is especially true for it a novice student decides to scan the entire internet with a 0.0.0.0/0 address scan. 
    // Depending on the learning objectives of your tutor, you may want to provide feedback on scan efficiency, but that is out of scope for this implementation.
    if (targetlist.includes(data[machine].IP) && ((data[machine].PortsClosed != "") || (data[machine].PortsFiltered != "") || (data[machine].PortsOpen != "") ) ) {
      // We're only going to give output if the machine exists AND would be discoverable by nmap. There could very well be machines that are in the dataset but not responding to packets from the scanned location (for example, due to firewalls)
      // Additionally, it would be good to add filtering here to check if the scan command included these ports, so we only display the asked-for ports. However, the current implementation would reject the student's input at the tutor level 
      // if the correct ports were not included, so this is not needed in this version. 
    	scannedaddresses += 1;
    	result += "Nmap scan report for " + data[machine].IP +"\r\n";
      result += "Host it up (" + data[machine].Latency + "s latency).\r\n"
      if (!pingScan) { result += "PORT         STATE    SERVICE\r\n"; }
      let allports = data[machine].PortsFiltered + " " + data[machine].PortsClosed + " " + data[machine].PortsOpen;
      let sortedports = allports.split(" ").sort((a, b) => Number(a) - Number(b));       
      for (let word in sortedports){
      	if (sortedports[word] != "") {
        	if (!pingScan) 
          { 
            result += sortedports[word] + "/tcp  ";
            if(data[machine].PortsFiltered.includes(sortedports[word])) {
              result += "filtered ";
            } else if (data[machine].PortsOpen.includes(sortedports[word])) {
              result += "open ";
            } else if (data[machine].PortsClosed.includes(sortedports[word])) {
              result += "closed ";
            }        
          	result += "\r\n";
          }
        }
      }
      if (!pingScan) { result += "\r\n"; }
    }
    
  }
  result += "Nmap done: " + totaladdresses + " IP addresses (" + scannedaddresses + " host up) scanned in 26.18 seconds\r\n" //total scan time is hardcoded, students did not appear to pay any attention to this metric, if needed/desired this can be modified in the future. 
  return result;
}

//If you're having trouble with your output/input these two lines will be a good way to verify programatically that everything is going well before mapping it into the page. 
//console.log(createPortScanResults(testdata));
//console.log(testdata);

//If you want to test in the browser, uncomment on of the following. UNCOMMENT ONLY ONE OF THESE AT A TIME!
// These are here for testing / showing you how this works. 
h1.textContent = createPortScanResults(testdata, "sudo nmap -sn -oN 172.16.0.1");
//h1.textContent = createPortScanResults(testdata, "sudo nmap -p 6881-6889 -oN 172.16.0.1-172.16.12.255"); 
//h1.textContent = createPortScanResults(testdata, "sudo nmap -p 6881-6889 -oN 172.16.0.1 172.16.0.3 172.16.0.2 172.16.0.4");
//h1.textContent = createPortScanResults(testdata, "sudo nmap -p 6881-6889 -oN 172-173.16-17.0-5.1-5");
//h1.textContent = createPortScanResults(testdata, "sudo nmap -p 6881-6889 -oN 172.16.0.1/24");
//h1.textContent = createPortScanResults(testdata, "sudo nmap -p 6881-6889 -oN 172.16.0-5.1-5");
//h1.textContent = createPortScanResults(testdata, "sudo nmap -p 6881-6889 -oN 172.16.0.1-3");
//h1.textContent = createPortScanResults(testdata, "sudo nmap -oN 172-173.16.0.1");
//h1.textContent = createPortScanResults(testdata, "sudo nmap -sV 172.16.0.1/24");
//Lets go crazy and mix all the syntaxes together! 
//h1.textContent = createPortScanResults(testdata, "sudo nmap -oN 172-173.16-18.0.1 172.16.0.3-172.16.0.20 172.16.5.4/26 8.8.8.8");

// Put the output on the page. 
document.body.appendChild(h1);

