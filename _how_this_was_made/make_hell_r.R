# Files of R's own formats for repo_from_hell, written to rfiles/
set.seed(666)
d <- data.frame(id = 1:200, group = sample(c("a", "b"), 200, TRUE),
                score = round(rnorm(200, 100, 15), 2))
out <- "rfiles"
save(d, file = file.path(out, "valid.RData"))
save(d, file = file.path(out, "rdata_named.R"))          # saved R data under a name ending in .R
writexl::write_xlsx(d, file.path(out, "valid.xlsx"))
file.copy(file.path(out, "valid.xlsx"), file.path(out, "excel_named.csv"))
sheets <- stats::setNames(lapply(1:50, \(i) d[sample(200, 20), ]), sprintf("Sheet %02d", 1:50))
writexl::write_xlsx(sheets, file.path(out, "many_sheets.xlsx"))
lab <- d
lab$group <- haven::labelled(ifelse(d$group == "a", 1, 2), c(control = 1, treatment = 2), label = "Condition")
haven::write_sav(lab, file.path(out, "valid.sav"))
saveRDS(d, file.path(out, "valid.rds"))
cat("ok\n")
