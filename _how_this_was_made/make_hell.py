# Builds repo_from_hell: a repository of every awkward file we could think of,
# for testing metacheck (scienceverse/metacheck). Files are added to git's
# storage directly (not written to disk first), because many of them cannot
# exist on Windows: forbidden characters, reserved names, names that differ
# only in case, paths over 260 characters, symbolic links and a submodule.
# Run from an empty folder with `git init` done; R's files come from
# make_hell_r.R (in rfiles/).
import gzip, io, json, os, random, subprocess, sys, tarfile, tempfile, unicodedata, zipfile

random.seed(666)
REPO = sys.argv[1]
RFILES = sys.argv[2]
SUBMODULE_COMMIT = sys.argv[3]
TMP = tempfile.mkdtemp()
entries = []

def git(*args, data=None):
    r = subprocess.run(["git", "-C", REPO, "-c", "core.protectNTFS=false", *args],
                       input=data, capture_output=True, check=True)
    return r.stdout.decode().strip()

def add(path, data=None, src=None, mode="100644"):
    if src is not None:
        sha = git("hash-object", "-w", src)
    else:
        if isinstance(data, str):
            data = data.encode("utf-8")
        sha = git("hash-object", "-w", "--stdin", data=data)
    entries.append((mode, sha, path))

def zip_bytes(members, compression=zipfile.ZIP_DEFLATED):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", compression) as z:
        for name, content in members:
            z.writestr(name, content)
    return b.getvalue()

def tar_bytes(members, gz=False):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz" if gz else "w") as t:
        for name, content in members:
            content = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(content)
            t.addfile(info, io.BytesIO(content))
    return b.getvalue()

def rbytes(name):
    with open(os.path.join(RFILES, name), "rb") as f:
        return f.read()

small_csv = "id,group,score\n" + "".join(
    f"{i},{random.choice('ab')},{random.gauss(100, 15):.2f}\n" for i in range(1, 101))
analysis_r = 'd <- read.csv("data/small.csv")\nt.test(score ~ group, data = d)\n'

# ── data that the other files point to ─────────────────────────────────────
add("data/small.csv", small_csv)
add("copies/small.csv", small_csv)                    # the same file twice
add("data/valid.xlsx", rbytes("valid.xlsx"))
add("data/valid.sav", rbytes("valid.sav"))
add("data/valid.RData", rbytes("valid.RData"))
add("data/valid.rds", rbytes("valid.rds"))
add("data/many_sheets.xlsx", rbytes("many_sheets.xlsx"))
add("data/many_columns.csv",
    ",".join(f"v{i}" for i in range(1, 10001)) + "\n" +
    "".join(",".join(str(random.randint(0, 9)) for _ in range(10000)) + "\n" for _ in range(50)))
add("data/mixed_separators_and_nul.csv", b"a,b;c\td\n1,2;3\t4\n5,\x006;7\t8\n\"unclosed,9\n")
add("data/trap_data.csv", "id,age,score\n1,23,10\n2,31,12\n3,27,9\n")
add("data/trap_data_codebook.csv",
    "variable,description\nparticipant,Participant number\ngender,Gender\niq,IQ score\n")

# ── archives ────────────────────────────────────────────────────────────────
normal_zip = zip_bytes([("analysis.R", analysis_r),
                        ("data.csv", "".join(f"{random.random()}\n" for _ in range(20000)))])
add("archives/truncated.zip", normal_zip[: len(normal_zip) // 2])
add("archives/tar_named.zip", tar_bytes([("inside_tar.R", analysis_r)]))
add("archives/zip_named.tar", zip_bytes([("inside_zip.R", analysis_r)]))
add("archives/empty.zip", zip_bytes([]))
level3 = zip_bytes([("deep.R", analysis_r), ("deep.csv", small_csv)])
level2 = zip_bytes([("level3.zip", level3), ("level2.R", "x <- 2\n")])
add("archives/nested.zip", zip_bytes([("level2.zip", level2), ("level1.R", "x <- 1\n")]))

# a zip that says its members are encrypted (general purpose flag bit 0)
pw = bytearray(zip_bytes([("secret.R", analysis_r), ("secret.csv", small_csv)]))
for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
    i = pw.find(sig)
    while i != -1:
        pw[i + off] |= 1
        i = pw.find(sig, i + 4)
add("archives/password.zip", bytes(pw))

add("archives/traversal.zip", zip_bytes([
    ("../escape.txt", "outside the folder\n"), ("/abs/etc_passwd.txt", "absolute\n"),
    ("..\\windows_escape.txt", "backslash\n"), ("ok/analysis.R", analysis_r)]))

# names in the old DOS characters (CP437), without the UTF-8 flag: written
# with placeholders of the same length, then the bytes replaced
cp = zip_bytes([("Baden-WXrttemberg.csv", small_csv), ("Z_rich_Stra_e.R", analysis_r)])
cp = cp.replace(b"Baden-WXrttemberg", b"Baden-W\x81rttemberg")
cp = cp.replace(b"Z_rich_Stra_e", b"Z\x81rich_Stra\xe1e")
add("archives/cp437_names.zip", cp)

import warnings
warnings.simplefilter("ignore")
add("archives/duplicate_members.zip", zip_bytes([("data.csv", "a\n1\n"), ("data.csv", "b\n2\n")]))

# __MACOSX folders and .DS_Store inside a zip, as macOS makes them
add("archives/macos_junk.zip", zip_bytes([
    ("study/analysis.R", analysis_r), ("__MACOSX/study/._analysis.R", b"\x00\x05\x16\x07junk"),
    ("study/.DS_Store", b"\x00\x00\x00\x01Bud1"), ("__MACOSX/._study", b"\x00\x05\x16\x07")]))

# large when unpacked: 500 MB in one member; 101 MB (just over the default
# per-file limit of 100 MB); 10,000 members; a gzip of 300 MB
def big_zip(path, name, size, line=b"0,0,0,0\n"):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z, z.open(name, "w", force_zip64=True) as f:
        block = line * (1024 * 1024 // len(line))
        written = 0
        while written < size:
            n = min(len(block), size - written)
            f.write(block[:n])
            written += n

p = os.path.join(TMP, "bomb.zip"); big_zip(p, "zeros.csv", 500 * 1024 * 1024)
add("archives/bomb_500MB.zip", src=p)
p = os.path.join(TMP, "big_member.zip"); big_zip(p, "big.csv", 101 * 1024 * 1024, b"1,2,3\n")
add("archives/member_101MB.zip", src=p)
add("archives/10000_members.zip",
    zip_bytes([(f"many/file_{i:05d}.csv", f"x\n{i}\n") for i in range(10000)]))
p = os.path.join(TMP, "gzbomb.csv.gz")
with gzip.open(p, "wb") as g:
    block = b"0,0,0,0\n" * (1024 * 1024 // 8)
    for _ in range(300):
        g.write(block)
add("archives/bomb_300MB.csv.gz", src=p)
add("archives/valid.tar.gz", tar_bytes([("in_targz/data.csv", small_csv), ("in_targz/run.R", analysis_r)], gz=True))
add("archives/not_compressed.csv.gz", small_csv)
add("archives/fake.7z", b"7z\xbc\xaf\x27\x1c\x00\x04" + os.urandom(2000))
add("archives/fake.rar", b"Rar!\x1a\x07\x00" + os.urandom(2000))
add("archives/corrupt.jasp", zip_bytes([("junk.txt", "not a JASP file\n")]))
add("archives/corrupt.omv", os.urandom(3000))

# ── empty files and folders ─────────────────────────────────────────────────
for name in ["empty.R", "empty.csv", "empty.xlsx", "empty.sav", "empty.ipynb", "empty.json",
             "empty.Rmd", "empty.py", "empty.do", "empty.zip.txt"]:
    add(f"empty/{name}", b"")
add("empty/bom_only.R", b"\xef\xbb\xbf")
add("empty/spaces_only.py", "    \n\t\n   ")
add("empty/newline_only.csv", "\n")
add("empty/folder_with_placeholder/.gitkeep", b"")
add("empty/a/b/c/d/.gitkeep", b"")

# ── wrong extensions ────────────────────────────────────────────────────────
add("wrong_extension/excel_named.csv", rbytes("excel_named.csv"))
add("wrong_extension/rdata_named.R", rbytes("rdata_named.R"))
add("wrong_extension/html_named.py",
    "<!DOCTYPE html><html><head><title>Sign in</title></head>"
    "<body><h1>404 Not Found</h1><p>Please sign in to continue.</p></body></html>\n")
add("wrong_extension/pdf_named.txt", b"%PDF-1.4\n1 0 obj<< /Type /Catalog >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n")
add("wrong_extension/text_named.sav", small_csv)
add("wrong_extension/broken.json", '{"study": "one", "n": 40, "items": [1, 2, ')
add("wrong_extension/text_named.xlsx", small_csv)
add("wrong_extension/png_named.R", b"\x89PNG\r\n\x1a\n" + os.urandom(5000))
add("wrong_extension/no_extension", analysis_r)
add("wrong_extension/.R", analysis_r)
add("wrong_extension/UPPER.CSV", small_csv)
add("wrong_extension/two.extensions.csv.R", analysis_r)

# ── languages ───────────────────────────────────────────────────────────────
L = "languages/"
add(L + "analysis.R", analysis_r)
add(L + "analysis.py", "import pandas as pd\nd = pd.read_csv('../data/small.csv')\nprint(d.groupby('group').score.mean())\n")
add(L + "analysis.do", 'import delimited "../data/small.csv", clear\nttest score, by(group)\nregress score i.group\n')
add(L + "analysis.sps", "GET DATA /TYPE=TXT /FILE='../data/small.csv' /DELIMITERS=','.\nT-TEST GROUPS=group('a' 'b') /VARIABLES=score.\n")
add(L + "analysis.sas", "proc import datafile='../data/small.csv' out=d dbms=csv replace; run;\nproc ttest data=d; class group; var score; run;\n")
add(L + "analysis.m", "d = readtable('../data/small.csv');\n[h, p] = ttest2(d.score(d.group == \"a\"), d.score(d.group == \"b\"))\n")
add(L + "analysis.jl", 'using CSV, DataFrames\nd = CSV.read("../data/small.csv", DataFrame)\nprintln(describe(d))\n')
add(L + "analysis.js", "const fs = require('fs');\nconst rows = fs.readFileSync('../data/small.csv', 'utf8').split('\\n');\nconsole.log(rows.length);\n")
add(L + "analysis.cpp", '#include <iostream>\nint main() { std::cout << "hello" << std::endl; return 0; }\n')
add(L + "model.inp", "TITLE: two groups;\nDATA: FILE IS ../data/small.dat;\nVARIABLE: NAMES ARE id group score;\nMODEL: score ON group;\n")
add(L + "report.Rmd", "---\ntitle: Report\noutput: html_document\n---\n\n```{r}\n" + analysis_r.replace("data/", "../data/") + "```\n\nThe mean was `r mean(d$score)`.\n")
add(L + "report_python.qmd", "---\ntitle: Python report\njupyter: python3\n---\n\n```{python}\nimport pandas as pd\nd = pd.read_csv('../data/small.csv')\nd.describe()\n```\n")
add(L + "notebook_r.ipynb", json.dumps({
    "cells": [{"cell_type": "code", "execution_count": 1, "metadata": {}, "outputs": [],
               "source": ["d <- read.csv('../data/small.csv')\n", "summary(d)\n"]}],
    "metadata": {"kernelspec": {"name": "ir", "language": "R", "display_name": "R"}},
    "nbformat": 4, "nbformat_minor": 5}))
add(L + "invalid.ipynb", '{"cells": [{"cell_type": "code", "source": ["x = 1"')
add(L + "utf16.R", "# Analysis saved in UTF-16\nx <- c(1, 2, 3)\nmean(x)\n".encode("utf-16"))
add(L + "latin1.R", "# Größe der Stichprobe\nlabel <- \"Mädchen\"\nx <- c(1, 2)\n".encode("latin-1"))
add(L + "cp1252.csv", 'name,remark\n"O\u2019Brien","\u201cquoted\u201d \u2013 dash"\n'.encode("cp1252"))
add(L + "old_mac_line_endings.R", "x <- 1\ry <- 2\rprint(x + y)\r".encode())
add(L + "mixed_line_endings.py", "a = 1\r\nb = 2\nc = 3\rprint(a + b + c)\n".encode())

# ── names ───────────────────────────────────────────────────────────────────
N = "names/"
for name in ["中文数据.csv", "بيانات.csv", "נתונים.R", "📊 data.csv", "file with spaces.R",
             "-leading-dash.R", "...", "#hash.R", "100%.csv", "semi;colon.R", "brackets[1](2){3}.R",
             "tab\tin name.R", "newline\nin name.R"]:
    add(N + name, analysis_r if name.endswith(".R") else small_csv)
add(N + unicodedata.normalize("NFC", "café_composed.csv"), small_csv)
add(N + unicodedata.normalize("NFD", "café_decomposed.csv"), small_csv)
add(N + unicodedata.normalize("NFC", "naïve.csv"), small_csv)
add(N + unicodedata.normalize("NFD", "naïve.csv"), small_csv)          # the same name, stored the other way
for name in ["CON.R", "nul.csv", "aux.txt", "COM1.py", "LPT1.do", "prn"]:
    add(N + "windows_reserved/" + name, analysis_r)
for name in ["what?.R", "a:b.csv", "star*.txt", 'quote".R', "lt<gt>.csv", "pipe|.py",
             "back\\slash.R", "trailing_dot.", "trailing_space.R "]:
    add(N + "windows_forbidden/" + name, analysis_r)
add(N + "case/Data.csv", small_csv)
add(N + "case/data.csv", "different,content\n1,2\n")
add(N + "case/DATA.CSV", "third,file\n3,4\n")
add(N + ("a_very_long_file_name_" * 9)[:196] + ".csv", small_csv)
deep = "/".join(f"level_{i:02d}_of_thirty_levels" for i in range(1, 31))
add("deep/" + deep + "/deep_analysis.R", analysis_r)
add("deep/" + deep + "/deep_data.csv", small_csv)

# ── symbolic links and a submodule ──────────────────────────────────────────
add("links/link_to_small.csv", "../data/small.csv", mode="120000")
add("links/broken_link.R", "missing.R", mode="120000")
add("links/loop_a", "loop_b", mode="120000")
add("links/loop_b", "loop_a", mode="120000")
add("links/link_to_folder", "../data", mode="120000")
add("links/absolute_link.csv", "C:/Users/someone/data.csv", mode="120000")
entries.append(("160000", SUBMODULE_COMMIT, "vendor/download-test"))
add(".gitmodules", '[submodule "vendor/download-test"]\n\tpath = vendor/download-test\n'
                   '\turl = https://github.com/Lakens/metacheck-download-test.git\n')

# ── Git LFS pointers (the real data is not in the repository) ───────────────
lfs = "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {}\n"
add("git_lfs/large_data.csv", lfs.format("4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", 734003200))
add("git_lfs/scans.sav", lfs.format("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", 52428800))

# ── junk that deposits often hold ───────────────────────────────────────────
add("junk/.DS_Store", b"\x00\x00\x00\x01Bud1" + os.urandom(100))
add("junk/Thumbs.db", os.urandom(500))
add("junk/~$lock_file.xlsx", os.urandom(165))
add("junk/.Rhistory", "x <- 1\nrm(list = ls())\nsetwd('C:/Users/me')\n")
add("junk/.hidden_data.csv", small_csv)
add("junk/__MACOSX/._small.csv", b"\x00\x05\x16\x07" + os.urandom(100))
add("junk/desktop.ini", "[.ShellClassInfo]\n")

# ── size ────────────────────────────────────────────────────────────────────
lines = [f"x{i} <- mean(c({random.random():.6f}, {random.random():.6f}))  # step {i}\n" for i in range(800000)]
add("size/big_script_40MB.R", "".join(lines))
add("size/one_line_10MB.R", "x <- c(" + ", ".join(str(i) for i in range(1, 1500000)) + ")\nlength(x)\n")
target = int(99.9 * 1024 * 1024)
p = os.path.join(TMP, "near_limit.csv")
with open(p, "w", newline="\n") as f:
    f.write("id,a,b,c\n")
    size, i = 9, 0
    while size < target:
        i += 1
        row = f"{i},{random.random():.8f},{random.random():.8f},{random.randint(0, 99999)}\n"
        if size + len(row) > target:
            break
        f.write(row)
        size += len(row)
add("size/just_under_100MB.csv", src=p)

# ── traps for the checks: code that behaves badly when run (harmless: nothing
#    deletes, writes outside its own folder, or uses the network) ────────────
T = "traps/"
add(T + "absolute_paths.R", 'setwd("C:/Users/someone/Documents/study")\nd <- read.csv("/home/someone/data/study.csv")\nsource("~/helpers.R")\n')
add(T + "installs_packages.R", 'install.packages("thispackagedoesnotexist123")\nlibrary(thispackagedoesnotexist123)\n')
add(T + "reads_missing_file.R", 'd <- read.csv("does_not_exist.csv")\n')
add(T + "reads_web_address.R", 'd <- read.csv("https://example.org/data/study.csv")\n')
add(T + "sources_missing_helper.R", 'source("helpers/missing_helper.R")\nhelper()\n')
add(T + "syntax_error.R", "x <- c(1, 2\ny <- function( { }\n")
add(T + "endless_loop_sleeping.R", "repeat {\n  Sys.sleep(1)\n}\n")
add(T + "endless_loop_busy.R", "i <- 0\nwhile (TRUE) {\n  i <- i + 1\n}\n")
add(T + "memory_2GB.R", "x <- list()\nfor (i in 1:20) x[[i]] <- numeric(1.25e7)  # 100 MB each\nprint(object.size(x), units = 'GB')\n")
add(T + "memory_impossible.R", "x <- numeric(1e12)  # 7,450 GB: refused at once\n")
add(T + "quits_r.R", 'cat("before\\n")\nquit(save = "no", status = 3)\ncat("never\\n")\n')
add(T + "kills_own_process.R", 'cat("stopping my own R process\\n")\ntools::pskill(Sys.getpid())\n')
add(T + "too_deep_recursion.R", "f <- function(n) f(n + 1)\nf(1)\n")
add(T + "floods_output.R", 'for (i in 1:1e6) cat("line", i, "\\n")\n')
add(T + "floods_warnings.R", "for (i in 1:10000) warning('warning number ', i)\n")
add(T + "waits_for_input.R", 'answer <- readline("Continue? ")\nchoice <- menu(c("yes", "no"))\n')
add(T + "writes_output.R", 'write.csv(data.frame(x = 1:3), "output_written_by_script.csv")\n')
add(T + "failing_chunk.Rmd", "---\ntitle: Fails\noutput: html_document\n---\n\n```{r}\nstop('this chunk fails')\n```\n")
add(T + "endless_loop.py", "while True:\n    pass\n")
add(T + "exits_with_error.py", "import sys\nprint('stopping')\nsys.exit(3)\n")
add(T + "imports_missing_module.py", "import thismoduledoesnotexist123\n")
add(T + "renv.lock", '{"R": {"Version": "4.3.1"}, "Packages": {"dplyr": {"Package": "dplyr", ')

# ── how this repository was made ────────────────────────────────────────────
here = os.path.dirname(os.path.abspath(__file__))
add("_how_this_was_made/make_hell.py", src=os.path.join(here, "make_hell.py"))
add("_how_this_was_made/make_hell_r.R", src=os.path.join(here, "make_hell_r.R"))

# ── into the index, as NUL-separated lines ──────────────────────────────────
info = b"".join(f"{m} {s}\t".encode() + p.encode("utf-8") + b"\0" for m, s, p in entries)
git("update-index", "-z", "--add", "--index-info", data=info)
print(len(entries), "entries")
