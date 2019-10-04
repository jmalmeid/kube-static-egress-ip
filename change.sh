
find . -type f | xargs grep -il kube- | grep -v .git | grep -v change.sh | grep -v lista_comm > /tmp/lista.txt

for a in `cat /tmp/lista.txt`
do
 vi $a < lista_comm.txt
done
