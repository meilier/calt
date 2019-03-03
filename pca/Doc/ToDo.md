# to do and bug list


## 2019/01/18 ----- done sign cmd mutex

Signature ok
Certificate Details:
        Serial Number: 0 (0x0)
        Validity
            Not Before: Certificate Details:
Jan 18 10:00:31 2019 GMT        Serial Number:
            Not After :  0 (0x0)
        Validity
Jan 15 10:00:31 2029 GMT            Not Before:
Jan 18 10:00:31 2019 GMT        Subject:

            Not After :  Jan 15 10:00:31 2029 GMT
         Subject:
                    countryName  countryName                            =  = CNC
N
                      stateOrProvinceName   stateOrProvinceName         =  Z H = EJZIHAENJGI
 A N  G
             organizationName              organizationName   =  Z J U
          =   Z J U
    organizationalUnitName    = ZJUCSCA
                      organizationalUnitName commonName     =  Z J U C S C A
           =  A C C O U N TcommonName1
          Certificate is to be certified until      = TLS1
Certificate is to be certified until Jan 15 10:00:31 2029 GMTJan 15 10:00:31 2029 GMT (3650 days) (3650 days)


Write out database with 1 new entries

Write out database with 1 new entries
Data Base Updated
**unable to rename /Users/xingweizheng/testrsa/serial.new to /Users/xingweizheng/testrsa/serial**
reason: No such file or directory
receiveProcess: wait client to send message

**bold sentence for handle double sign process at the same time, so it needs to add a lock to run sign cmd.**

Three below for fast multi-thread exec all the process

## 1⃣️ muli-thread synchronization -- done

## 2⃣️ message split -- done

## 3⃣️ config file for every nodes -- done

## change thread loop to semaphore -done

## bug1

Cert::getCertFileName : returnmsg is /Users/xingweizheng/testecc/requests/account/accountCert1.csrfileProcess: why thead not return 538

//here not continue to execute
fileProcess: why thead not return 0
should be ready to return
start to sign cert

            csrfile.close();
            //send file get ok message to handle process
            certType == 0 ? hq.Push(GACO) : hq.Push(GTCO);
            printf("should be ready to return\n");
            return;
        309 not put message to hq

### bug 1 --solusion

    You need to close socket first, otherwise the server will still wait data coming.

    244 printf("sendProcess: send csr successfully\n");
        //may be the bug is you need to close socket first
        close(file_cli);
        sfile.close();
        //send file get ok message to handle process
        //may be h

## bug 2

Write out database with 1 new entries
Data Base Updated
Cert::getCertFileName : returnmsg is /Users/xingweizheng/testecc/certs/account/accountCert1.pem

//here the server stop to run  --1⃣️
reveiceProcess: the message is
start message listening thread at 7000 // here prove that sema works because of the absence of client
wrong message
reveiceProcess: the message is
wrong message
reveiceProcess: the message is
wrong message

next, I'll see why sq.Push(SAO) don't work.
            if (hqmessage == GACO)
            {
                //sign account certificate
                mCert->signCert("account");
                sq.Push(SAO);
        249 }
