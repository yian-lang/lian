
draw.matrix <- function(M) {
  # default args require transpose: col, row => x, y
  image(1:ncol(M), 1:nrow(M), t(M)[, nrow(M):1], xlab="", ylab="")
}

fnv.32 <- as.matrix(read.table("data/fnv_32.txt", header=FALSE))
fnv.mw <- as.matrix(read.table("data/fnv_mw.txt", header=FALSE))

png(filename="data/fnv_32vMW.png", width=720, height=480)
nf <- layout(matrix(c(1,2), 1, 2), widths=c(1,3), heights=c(1,1))

draw.matrix(fnv.32)
draw.matrix(fnv.mw)
dev.off()
