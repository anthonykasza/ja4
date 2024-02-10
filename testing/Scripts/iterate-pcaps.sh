
SCRIPT_DIR="/ja4/scripts";
declare -a PCAP_DIRS=("tls" "quic" "rdp")

for PCAP_DIR in ${PCAP_DIRS[@]}; do
  for FULL_FN in `ls /Traces/${PCAP_DIR}/*`; do
    FN=`echo ${FULL_FN} | awk -F '/' '{print $NF}' | awk -F '.' '{print $1}'`;
    zeek ${SCRIPT_DIR} ./make-btests.zeek -Cr ${FULL_FN} > ${FN}_btest.zeek;
  done;
done;

rm *.log;
find . -size 0 -delete;
mv *_btest.zeek ../tests
