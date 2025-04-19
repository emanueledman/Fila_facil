#!/bin/bash
# apply_sql.sh
psql $DATABASE_URL -f update_ticket_table.sql