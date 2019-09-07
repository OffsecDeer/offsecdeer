<!--+++
aliases = ["posts","articles","blog","showcase","docs"]
title = "Posts"
+++

{{ range sort .Paginator.Pages }}

{{ if isset .Params "page"}}
<!-- do nothing: do not list content in /pages/ -->

{{ else }}
    <h2><a href="{{ .Permalink }}">{{ .Title }}</a></h2>
    <p class="timestamp">{{ .Date.Format "January 2, 2006" }}</p>
    <div class="content">
    {{ if isset .Params "description" }}
        {{ index .Params "description" }}
    {{ else }}
        {{ .Summary | plainify | safeHTML }}
        {{ if .Truncated }}
            ... <a href="{{ .Permalink }}">Read more &hellip;</a>
        {{ end }}
    {{ end }}
    </div>
    {{ if .Params.tags }}
      {{ partial "tags" .Params.tags }}
    {{ end }}
{{ end }}
{{ end }}

{{ partial "pagination.html" . }}
-->
