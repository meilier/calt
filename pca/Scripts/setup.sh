# setup dir
ScirptPath=$(cd `dirname $0`; pwd)
echo $ScirptPath
source $ScirptPath/header.sh
mkdir -p $CAPATH
cp $WORKDIR/Scripts/openssl.cnf $CAPATH/
mkdir -p $CAPATH/certs/account $CAPATH/certs/tls
mkdir -p $CAPATH/requests/account $CAPATH/requests/tls
mkdir -p $CAPATH/crl $CAPATH/private $CAPATH/newcerts
touch $CAPATH/index.txt

# test crl file
echo 'aaaaaaaaaaa' > $CAPATH/crl/invoke.crl

echo '00' > $CAPATH/serial
echo "set up directoty ok" 

# create ca root private key and pem
# openssl genrsa -aes256  -passout pass:$CAPASS -out $CAPATH/private/cakey.pem 2048
openssl ecparam -name secp384r1 -genkey | openssl ec -aes-256-cbc -passout pass:$CAPASS -out $CAPATH/private/cakey.pem
chmod 400 $CAPATH/private/cakey.pem
openssl req -config $CAPATH/openssl.cnf -key $CAPATH/private/cakey.pem -new -extensions ext_root -out $CAPATH/private/cacert.pem -x509 -passin pass:$CAPASS -subj /C=$COUNTRYNAME/ST=$STATEPROVINCENAME/O=$ORGNAME/OU=$ORGUNITNAME/CN=$COMMONNAMECA -days 7300
chmod 444 $CAPATH/private/cacert.pem
# copy ca certs to certs dir
cp $CAPATH/private/cacert.pem $CAPATH/certs/cacert.pem
echo "generate ca file ok"

# done 
echo "done everything"
exit