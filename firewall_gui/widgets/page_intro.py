"""Shared page heading with a short, scannable purpose statement."""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk


def page_intro(title, description, icon_name):
    group = Adw.PreferencesGroup()
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
    box.add_css_class("page-intro")
    image = Gtk.Image.new_from_icon_name(icon_name)
    image.set_pixel_size(36)
    image.set_valign(Gtk.Align.START)
    image.add_css_class("page-intro-icon")
    box.append(image)
    copy = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    title_label = Gtk.Label(label=title, xalign=0)
    title_label.add_css_class("title-1")
    copy.append(title_label)
    description_label = Gtk.Label(label=description, xalign=0, wrap=True)
    description_label.add_css_class("dim-label")
    copy.append(description_label)
    box.append(copy)
    group.add(box)
    return group
