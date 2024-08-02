#!/bin/bash
mkdir sig
root=./
pelf=$root/flair75/bin/linux/pelf
sigmake=$root/flair75/bin/linux/sigmake
for lib in ./libs/*.a
do
    libn=`basename "$lib"`
    libn=${libn::-2}
    $pelf "$lib" "$libn.pat"    
    $sigmake "$libn.pat" "$libn.sig"
    if [ -f "$libn.exc" ]; then
	    sed -i '/^;/ d' "$libn.exc"
    fi
    $sigmake "$libn.pat" "$libn.sig"
done
mv *.sig sig/
rm *.pat
rm *.exc
