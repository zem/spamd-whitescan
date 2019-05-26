#!/bin/ksh
# 
# This is a verry crude first example of how to import whitescan 
# lists to a whitescan instand and how to export them 
# 
WHITESCAN=/root/whitescan.pl
EXPORT=/root/spamd-whitescan-export/

cd ${EXPORT}
git pull || exit $?
${WHITESCAN} -i ${EXPORT} || exit $?
if [[ $1 == "push" ]]
then
        ${WHITESCAN} -e ${EXPORT} || exit $?
        git commit -m "updated records" || exit 0
        git push
fi

