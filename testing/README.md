

```
rm *.log; for EACH in `ls ../zeek/testing/btest/Traces/tls/*`; do PCAP=`echo ${EACH} | awk -F "/" '{print $7}'`; ../zeek-install/bin/zeek ../ja4/scripts/ -Cr ${EACH}; mv ja4.log "ja4_${PCAP}.log" ; echo ${EACH}; done > errors.log 2>&1; for EACH in `ls ja4_*`; do echo ${EACH}; grep -v '^#' ${EACH} | awk -F '\t' '{print $2, $3, $4, $5, $6}'; done > output.log
```

