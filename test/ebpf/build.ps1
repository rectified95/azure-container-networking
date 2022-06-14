rm ebpf.exe
rm src/*.o
go build 
cd src/
clang -g -I C:\Users\azureuser\ebpf-for-windows\include  -I C:\Users\azureuser\ebpf-for-windows\external\bpftool -target bpf -Werror -O2 -c .\endpoint_prog.c -o endpoint_prog.o
cd ..
git add ebpf.exe src/*.o