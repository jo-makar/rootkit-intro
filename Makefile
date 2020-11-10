rootkit-objs := base.o execve.o getdents.o hook.o kill.o mkdir.o random.o
obj-m += rootkit.o

# Disable tail recursion optimizations to avoid interfering with ftrace hooks.
# Add V=1 to the make rules below to display the full commands used.
ccflags-y := -fno-optimize-sibling-calls

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

