##########################################
# EMULATOR
##########################################

BUILD_DIR 		:= build
HANDOUT_DIR		:= handout
SCRIPTS_DIR		:= scripts

HANDOUTS		:= $(HANDOUT_DIR)/hackvm.tar.gz $(HANDOUT_DIR)/vmhack.tar.gz

RELEASE_TARGET 	:= $(BUILD_DIR)/vm
DEBUG_TARGET	:= $(BUILD_DIR)/vm_debug

DEBUG_FLAGS		:= -g3 -ggdb -DDEBUG -O0 -fsanitize=address,leak
RELEASE_FLAGS	:= -O1 -DNDEBUG -fno-stack-protector -static

.PHONY: 	release clean debug all puzzles handout
all: 		handout debug release puzzles

$(RELEASE_TARGET): vm.c
	musl-gcc -o $@ $^ -Wall -Werror -std=gnu11 $(RELEASE_FLAGS)
	strip --discard-all $(shell cat symbols.txt | awk '{print "--strip-symbol=" $$1}') $@

$(DEBUG_TARGET): vm.c
	gcc -o $@ $^ -Wall -Werror -std=gnu11 $(DEBUG_FLAGS)

##########################################
# USER PROGRAMS
##########################################

U			:= user
O			:= tmp

CC			:= riscv32-unknown-elf-gcc
LD			:= riscv32-unknown-elf-ld
OBJDUMP		:= riscv32-unknown-elf-objdump
STRIP		:= riscv32-unknown-elf-strip
ELFEDIT		:= riscv32-unknown-elf-elfedit

CFLAGS		:= -Wall -Werror -O1 -fno-inline -ffreestanding -nostdlib -march=rv32im -mabi=ilp32 -I. -mno-relax
SFLAGS		:= -d --remove-section .riscv.attributes --remove-section .comment

UTARGET		:= $(BUILD_DIR)/example $(BUILD_DIR)/puzzle1 $(BUILD_DIR)/puzzle2
ULIB		:= $(BUILD_DIR)/$(O)/usys.o $(BUILD_DIR)/$(O)/ulib.o

$(BUILD_DIR)/$(O)/%.o: $(U)/%.c
	@mkdir -p $(@D)
	$(CC) -o $@ -c $^ $(CFLAGS)

$(U)/puzzle2.c: $(U)/puzzle2.h

$(U)/puzzle2.h:
	$(SCRIPTS_DIR)/puzzle2_codegen.py $(BUILD_DIR)/$(O)/constraints $@

$(BUILD_DIR)/$(O)/%.o: $(U)/%.S
	@mkdir -p $(@D)
	$(CC) -o $@ -c $^ $(CFLAGS)

$(BUILD_DIR)/%: $(BUILD_DIR)/$(O)/%.o $(ULIB)
	$(LD) -T $(U)/user.ld -o $@ $^
	$(OBJDUMP) -S $@ > $(BUILD_DIR)/$(O)/$*.asm
	$(STRIP) $(SFLAGS) $@
	$(ELFEDIT) --output-mach none $@

# Prevent deletion of intermediate files, e.g. cat.o, after first build, so
# that disk image changes after first build are persistent until clean.
# http://www.gnu.org/software/make/manual/html_node/Chained-Rules.html
.PRECIOUS: $(BUILD_DIR)/$(O)/%.o

##########################################
# NAMED TARGETS
##########################################

$(HANDOUT_DIR)/hackvm.tar.gz: $(RELEASE_TARGET) $(BUILD_DIR)/puzzle1
	cd build && tar -cvzf ../$@ vm puzzle1

$(HANDOUT_DIR)/vmhack.tar.gz: $(RELEASE_TARGET) $(BUILD_DIR)/puzzle2
	cd build && tar -cvzf ../$@ vm puzzle2

release: 	$(RELEASE_TARGET)
debug: 		$(DEBUG_TARGET)
puzzles:	$(UTARGET)
handout: 	$(HANDOUTS)

clean:
	-rm -rf $(BUILD_DIR)/*
	-rm -rf $(HANDOUT_DIR)/*
	-rm $(U)/puzzle2.h