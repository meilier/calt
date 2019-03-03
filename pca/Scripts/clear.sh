# here we may back these files first 
ScirptPath=$(cd `dirname $0`; pwd)
echo $ScirptPath
source $ScirptPath/header.sh
cd $CAPATH
CUR=`pwd`
echo "CAPATH is " $CAPATH
echo "CUR is" $CUR
if [ $CUR = $CAPATH ]
then
    echo "start to clean"
    rm -rf certs crl index* newcerts openssl.cnf private requests serial* crlnumber*
else
    echo "oh, my god!"
fi
#
echo "clean all"

