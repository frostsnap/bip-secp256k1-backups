SRC := README.md
PDF := $(SRC:.md=.pdf)
VERSION := $(shell git log -1 --format=%h -- $(SRC))$(shell git diff --quiet HEAD -- $(SRC) || echo -dirty)
VERSION_DATE := $(shell git log -1 --format=%cs -- $(SRC))

all: $(PDF)

%.pdf: %.md template.tex FORCE
	pandoc --from=markdown --to=pdf \
		--pdf-engine=xelatex \
		--template=template.tex \
		--highlight-style=monochrome \
		-V version=$(VERSION) \
		-V version-date=$(VERSION_DATE) \
		--output=$@ $<

clean:
	rm -f $(PDF)

FORCE:

.PHONY: all clean FORCE
