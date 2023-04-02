all: httpd client  # 构建哪些，如果只运行make，就是构建all
LIBS = -pthread # dont use -lsocket or -lpthread

# $@ 目标文件， $< 第一个依赖文件
# -g: 可供GDB调试, -W: 
httpd: httpd.c
	gcc -g -W -Wall $(LIBS) -o $@ $<

client: simpleclient.c
	gcc -W -Wall -o $@ $<
clean:
	rm httpd client
