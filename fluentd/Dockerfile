FROM fluent/fluentd:v1.16-debian-1
USER root
RUN gem install fluent-plugin-concat \
    && gem install fluent-plugin-rewrite-tag-filter
USER fluent