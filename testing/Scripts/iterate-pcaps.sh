
SCRIPT_DIR="/ja4/scripts";

PCAP_DIR="/Traces/tls";
for FULL_FN in `ls ${PCAP_DIR}/*`;
  do FN=`echo ${FULL_FN} | awk -F '/' '{print $NF}' | awk -F '.' '{print $1}'`;
  zeek ${SCRIPT_DIR} ./make-btests.zeek -Cr ${FULL_FN} > ${FN}_btest.zeek;
done;

PCAP_DIR="/Traces/quic";
for FULL_FN in `ls ${PCAP_DIR}/*`;
  do FN=`echo ${FULL_FN} | awk -F '/' '{print $NF}' | awk -F '.' '{print $1}'`;
  zeek ${SCRIPT_DIR} ./make-btests.zeek -Cr ${FULL_FN} > ${FN}_btest.zeek;
done;

rm *.log;
find . -size 0 -delete;
mv *_btest.zeek ../tests
